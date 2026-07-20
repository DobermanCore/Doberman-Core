"""OpenClaw host-hook adapter — gate an OpenClaw agent's tool calls through
Doberman's deterministic objective floor.

OpenClaw exposes a typed **plugin** hook, ``before_tool_call``
(``api.on("before_tool_call", handler)`` — see ``adapters/openclaw/``), fired for
every tool call before it executes. The plugin's JS entry spawns this adapter's
CLI command (``doberman hook openclaw``) as a fresh subprocess per call, writes the
event as JSON on stdin, and reads exactly one JSON verdict back from stdout under
a hard ~10s timeout. Any spawn failure, timeout, non-zero exit, or unparseable
stdout is the shim's own problem, not ours — but per ADR 0038 the shim FAILS
CLOSED in every one of those cases, so this module's job is simple: **always
answer, and never take longer than the shim is willing to wait.**

Unlike :mod:`doberman.hosthooks.claude_code` (whose ``run_pre_hook`` prints
*nothing* to abstain — Claude Code's own hook protocol treats silence as
"allow"), this module's subprocess-per-call bridge has no such convention: no
output before the timeout is indistinguishable from a hang, and the shim fails
closed on a hang. So :func:`run_before_tool_call_hook` **always** returns a
single JSON document — ``{"verdict": "allow"}`` included.

**Verdict -> OpenClaw mapping** (see ``adapters/openclaw/index.js``):

* ``allow`` -> no-op (``{}`` from the plugin hook) - Doberman is raise-only, it
  never overrides an approval OpenClaw would otherwise grant.
* ``block`` -> ``{block: true, blockReason}`` - terminal, no lower-priority hook runs.
* ``auth``  -> ``{requireApproval: {...}}``. Unlike the Claude Code hook (which
  runs Doberman's own GUI/TTY challenge synchronously in-process), OpenClaw's
  ``before_tool_call`` runs inside a headless gateway process with no
  interactive terminal of its own — so AUTH here delegates to **OpenClaw's own**
  ``/approve`` flow (``allowedDecisions: ["allow-once", "deny"]`` — deliberately
  no ``"allow-always"``: a standing approval is Doberman's own policy surface,
  not something the host should be allowed to memorize around us). An
  unresolved or denied approval is a deny by OpenClaw's own contract.

**Tool recognition — gate-by-default, not allowlist-by-default.** Claude Code's
hook only evaluates a small, closed set of built-ins (``GATED_BUILTINS``) plus
``mcp__``-prefixed tools; everything else abstains, because Claude Code's
built-in tool catalog is small, stable, and fully documented. OpenClaw's is not
(the public docs explicitly do not publish an exhaustive tool-name or
``toolKind`` enum). So this module inverts the default: only one
confirmed-safe tool (:data:`_ABSTAIN_TOOLS` - ``session_status``, an internal
status call with no path/command/network surface) abstains; every other tool
name - known built-in, MCP-provided, or a name we've simply never seen - is
normalized and run through the real decision path. ``read`` is deliberately
NOT in ``_ABSTAIN_TOOLS``: it is normalized to ``read_file`` and its
``params.path`` is gated by :class:`~doberman.engine.rules.paths.ProtectedPathRule`
the same as every other action, so a `.env`/key/control-plane read is blocked
or authenticated exactly like a write to the same path — this adapter has no
``after_tool_call`` hook in this slice, so pre-gating the read *target* by path
is the only defense it has; the read's *content* still isn't scanned (a
documented limitation, not a loophole; see ``adapters/openclaw/README.md``).
An unrecognized tool with nothing suspicious in its arguments still comes back
``allow`` (that is ordinary guardrail behavior, not a loophole); the point is
it is never skipped without being looked at.

**Confirmed vs. best-effort field names.** ``exec``'s ``params.command``,
``web_search``'s ``params.query``, and ``read``'s ``params.path`` are
confirmed against OpenClaw's own docs / issue tracker (``read``'s ``path`` key
via openclaw/openclaw#2596 and #16717, two independent bug reports of agents
mistakenly sending ``file_path`` instead). ``web_fetch``'s ``params.url`` is
inferred by convention (not independently confirmed) - if wrong, ``web_fetch``
calls fail closed (denied) until corrected, which is safe, just overly strict;
see the module's ``_REQUIRED_FIELD`` comment.

**Speed.** Like the Claude Code hook, this module imports only the light
deterministic path — never :mod:`doberman.proxy.executor` or the subjective
baseline (``numpy``/``scipy``/``river`` at module scope).
"""

from __future__ import annotations

import json
from typing import Any

from doberman.branding import DOG
from doberman.config import load_active_role, load_mode, resolve_enforcement_sync
from doberman.engine.decision_engine import PASS_STUB, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.taint_floor import apply_taint_floor
from doberman.models import Decision, EvalContext, Risk, SecurityObject, Verdict
from doberman.policy.drift import acted_verdict
from doberman.policy.modes import DEFAULT_MODE
from doberman.proxy.normalize import normalize

#: Tool names that carry no path/command/network surface to gate at all - an
#: internal status call, never a mutation, execution, or egress. Deliberately
#: does NOT include "read": a read's *target path* is gated like any other
#: file-touching action (see ``_CANONICAL_RENAME`` / ``_REQUIRED_FIELD`` below
#: and the module docstring's "Tool recognition" section); only the read's
#: *content* goes unscanned in this slice.
_ABSTAIN_TOOLS: frozenset[str] = frozenset({"session_status"})

#: Rename a tool name to the canonical name :func:`doberman.proxy.normalize.normalize`
#: already maps to the right :class:`~doberman.models.ActionType` via its
#: prefix table. ``"read"`` -> ``"read_file"`` mirrors
#: :mod:`doberman.hosthooks.claude_code`'s own ``"Read"`` mapping and lands on
#: ``ActionType.file_read``, so its ``path`` is gated by
#: :class:`~doberman.engine.rules.paths.ProtectedPathRule` like any other
#: file-touching action. ``exec``/``web_search``/anything else pass through
#: unchanged: ``normalize``'s own prefix table already recognizes literal
#: ``"exec"`` as ``shell_exec``, and an unmapped name safely falls to
#: ``ActionType.other`` (still scanned generically - see the module docstring).
_CANONICAL_RENAME: dict[str, str] = {
    "read": "read_file",
    "web_fetch": "http_request",
    "apply_patch": "file_write",
}

#: A gated tool must expose the field that identifies its action, else we
#: cannot see what we are being asked to gate and fail closed (deny) rather
#: than abstain - mirrors ``claude_code._REQUIRED_FIELD``. Keyed on the
#: pre-rename tool name (e.g. "read", not "read_file"), so this check runs
#: before ``_CANONICAL_RENAME`` is applied.
#: CONFIRMED: "exec" -> "command" (openclaw/openclaw plugin issue tracker
#: example rewriting ``event.params.command``); "web_search" -> "query"
#: (docs.openclaw.ai/plugins/hooks quick-start example, ``event.params.query``);
#: "read" -> "path" (openclaw/openclaw#2596 and #16717, two independent bug
#: reports of agents mistakenly sending "file_path" instead of the tool's
#: actual "path" key).
#: BEST-EFFORT (not independently confirmed): "web_fetch" -> "url", inferred by
#: convention from web_search's "query" and Claude Code's own WebFetch tool. If
#: OpenClaw's real key differs, web_fetch calls will always deny here (safe,
#: just overly strict) until this one line is corrected against a live install.
_REQUIRED_FIELD: dict[str, str] = {
    "exec": "command",
    "read": "path",
    "web_fetch": "url",
    "web_search": "query",
}

_FAILSAFE_REASON = DOG + " Doberman: failing closed - could not evaluate this action safely."
_REASON = DOG + " Doberman [{verdict}]: {explanation} (reasons: {reasons}; action {action_id})"
_NEXT_STEP = (
    "Next step: this BLOCK has no in-session override. If this is trusted "
    "administrative work, run it through a channel outside this OpenClaw-mediated agent."
)
#: How long OpenClaw waits for a human to resolve a ``requireApproval`` before
#: treating it as denied. Longer than a local GUI-dialog timeout on purpose:
#: this is an async, chat-mediated approval (``/approve``), not a synchronous
#: dialog the operator is already looking at.
_AUTH_APPROVAL_TIMEOUT_MS = 300_000

_VERDICT_ALLOW: dict[str, Any] = {"verdict": "allow"}


def to_normalize_input(
    tool_name: str,
    params: dict[str, Any] | None,
    derived_paths: list[str] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Translate an OpenClaw tool call into ``normalize()``'s ``(name, args)``.

    ``apply_patch`` carries no natural path key (its params are an opaque patch
    envelope) - OpenClaw's host-derived ``derivedPaths`` hint fills the ``path``
    key ``normalize`` looks for, when the call doesn't already have one. Never
    raises.
    """
    args = dict(params or {})
    canonical = _CANONICAL_RENAME.get(tool_name, tool_name)
    if canonical == "file_write" and not any(
        isinstance(args.get(k), str) and args[k] for k in ("path", "file", "filename")
    ):
        paths = derived_paths or []
        if paths:
            args["path"] = paths[0]
    return canonical, args


def _format_reason(decision: Decision, verdict_label: str) -> str:
    """The redaction-safe reason line - built only from already-safe decision
    fields (explanation + reason codes + action id), never a raw argument value."""
    return _REASON.format(
        verdict=verdict_label,
        explanation=(decision.explanation or "").strip() or "no further detail",
        reasons=", ".join(str(rc) for rc in decision.reason_codes) or "unspecified",
        action_id=decision.action_id,
    )


def _verdict_block(reason: str) -> dict[str, Any]:
    return {"verdict": "block", "reason": reason}


def _verdict_auth(decision: Decision) -> dict[str, Any]:
    if decision.final_risk in (Risk.critical, Risk.high):
        severity = "critical"
    elif decision.final_risk is Risk.medium:
        severity = "warning"
    else:
        severity = "info"
    return {
        "verdict": "auth",
        "title": f"Doberman approval required ({decision.final_risk.value} risk)",
        "description": _format_reason(decision, "AUTH"),
        "severity": severity,
        "timeout_ms": _AUTH_APPROVAL_TIMEOUT_MS,
    }


def _resolve_root_and_mode(cwd: object) -> tuple[str, str]:
    """Resolve ``(repo_root, strictness_mode)`` from the hook payload's ``cwd``.

    Mirrors ``claude_code._resolve_root_and_mode``: a missing/invalid ``cwd``
    must NOT fall back to ``load_mode(".")`` (a different project's policy, or
    none - possibly weaker than the real project's). OpenClaw's ``before_tool_call``
    exposes no working-directory field of its own (confirmed absent from the
    published event/context docs); the plugin shim sends ``process.cwd()`` on a
    best-effort basis, so this still resolves real per-project policy when the
    gateway happens to run from the project root, and falls back safely otherwise.
    """
    if isinstance(cwd, str) and cwd:
        return cwd, load_mode(cwd)
    return ".", DEFAULT_MODE.value


def _record_history(
    decision: Decision,
    action: SecurityObject,
    repo_root: str,
    session_id: str | None,
    *,
    auth_result: str,
) -> None:
    """Best-effort: persist one decision row to the local decision log.

    Only called for BLOCK and monitor-softened outcomes - both known
    immediately. An AUTH's eventual resolution happens asynchronously via
    OpenClaw's own ``/approve`` flow, outside this process's lifetime, so
    (unlike the Claude Code hook) it is not recorded here - recording it would
    need a second round-trip through ``onResolution``, out of scope for this
    slice (see ``adapters/openclaw/README.md``). Wrapped in a broad except - a
    recording failure must never affect the hook's return value.
    """
    import asyncio  # lazy import keeps the module scope light

    from doberman.storage.log import record_decision  # lazy import

    try:
        asyncio.run(
            record_decision(
                decision,
                action,
                repo_root=repo_root,
                auth_result=auth_result,
                session_id=session_id,
            )
        )
    except Exception:  # noqa: BLE001,S110 — history must never break the hook path
        pass


def evaluate_before_tool_call(payload: dict[str, Any]) -> dict[str, Any]:
    """Decide one ``before_tool_call`` event.

    Always returns a verdict dict (``allow`` / ``auth`` / ``block``) - never
    ``None``. NEVER raises - any failure becomes a ``block`` (fail closed).
    """
    try:
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            return _verdict_block(_FAILSAFE_REASON)  # no identifiable action -> refuse

        if tool_name in _ABSTAIN_TOOLS:
            return _VERDICT_ALLOW  # known-safe read / internal status call

        raw_params = payload.get("params")
        params = raw_params if isinstance(raw_params, dict) else {}

        raw_derived = payload.get("derived_paths")
        derived_paths = (
            [p for p in raw_derived if isinstance(p, str) and p]
            if isinstance(raw_derived, list)
            else []
        )

        canonical, args = to_normalize_input(tool_name, params, derived_paths)

        # Fail closed: a gated tool whose required input field is missing/empty,
        # or a file-touching tool we can't identify a target path for, is an
        # action we cannot actually see - refuse it rather than abstain.
        required = _REQUIRED_FIELD.get(tool_name)
        if required is not None:
            value = args.get(required)
            if not isinstance(value, str) or not value.strip():
                return _verdict_block(_FAILSAFE_REASON)
        if canonical == "file_write" and not (
            isinstance(args.get("path"), str) and args["path"].strip()
        ):
            return _verdict_block(_FAILSAFE_REASON)

        repo_root, mode = _resolve_root_and_mode(payload.get("cwd"))
        raw_session = payload.get("session_id")
        session_id = raw_session if isinstance(raw_session, str) and raw_session else None

        action = normalize(canonical, args)
        # The objective rules inspect the UN-redacted call via
        # metadata['raw_arguments'] (in-memory only, never logged). The active
        # role rides along too (parity with the Claude Code hook / proxy).
        ctx = EvalContext(
            role=load_active_role(repo_root),
            mode=mode,
            metadata={"raw_arguments": args, "repo_root": repo_root},
        )
        decision = decide(action, ObjectiveGuardrail(), PASS_STUB, ctx)
        decision = apply_taint_floor(action, decision, ctx.mode, repo_root, session_id, args)
        enforcement = resolve_enforcement_sync(repo_root)
        acted = acted_verdict(decision, enforcement)

        if acted is Verdict.PASS:
            if enforcement == "monitor" and decision.final_verdict is not Verdict.PASS:
                # A would-be AUTH/BLOCK softened by MONITOR is history-worthy:
                # record the ORIGINAL (truthful) decision, outcome "executed"
                # (a synthetic allow) - matches claude_code's monitor branch.
                _record_history(decision, action, repo_root, session_id, auth_result="executed")
            return _VERDICT_ALLOW  # raise-only: let OpenClaw's native flow continue
        if acted is Verdict.AUTH:
            return _verdict_auth(decision)  # delegate to OpenClaw's own /approve flow
        result = _verdict_block(
            f"{_format_reason(decision, decision.final_verdict.name)} {_NEXT_STEP}"
        )
        _record_history(decision, action, repo_root, session_id, auth_result="blocked")
        return result
    except Exception:  # noqa: BLE001 — fail closed; never surface the payload in an error
        return _verdict_block(_FAILSAFE_REASON)


def run_before_tool_call_hook(stdin_text: str) -> str:
    """Parse the hook stdin, evaluate, and return the JSON string to print to
    stdout - ALWAYS exactly one JSON document (see module docstring: this
    bridge has no "silence means allow" convention, unlike the Claude Code hook).

    A payload that does not parse to a JSON object is denied: an unidentifiable
    call fails closed rather than slipping through.
    """
    try:
        payload = json.loads(stdin_text)
    except Exception:  # noqa: BLE001 — unparseable input denies the unknown call
        return json.dumps(_verdict_block(_FAILSAFE_REASON))
    if not isinstance(payload, dict):
        return json.dumps(_verdict_block(_FAILSAFE_REASON))
    return json.dumps(evaluate_before_tool_call(payload))
