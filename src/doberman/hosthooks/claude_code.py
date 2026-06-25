"""Claude Code host-hook adapter — make Doberman enforce on an agent's tool
calls without the agent opting in.

Claude Code can run a command as a ``PreToolUse`` hook *before* every tool call.
Wired in (see ``doberman install-hooks``, a later slice), the harness invokes
``doberman hook pre`` and hands this adapter the tool call on stdin. We translate
it into a :class:`~doberman.models.SecurityObject`, run the **deterministic
objective floor**, and answer in Claude Code's hook protocol:

* ``PASS``  -> abstain (no output). Doberman is **raise-only**: it never removes
  the harness's own permission prompts, it only *adds* friction.
* ``AUTH``  -> ``permissionDecision: "ask"`` — the harness asks the human.
* ``BLOCK`` -> ``permissionDecision: "deny"`` with a redaction-safe reason.

**Fail closed.** A malformed payload, an engine error, or any unhandled case
denies the call — if we cannot identify an action, we refuse it. The reason text
is built only from ``Decision.explanation`` + ``reason_codes`` (already
redaction-safe); no raw argument value is ever echoed back to the agent.

**Speed.** A ``PreToolUse`` hook runs before *every* tool call, so this module
imports only the light decision path (``normalize`` + the objective guardrail +
``decide``). It must NEVER import :mod:`doberman.proxy.executor` or the subjective
baseline — those pull ``numpy``/``scipy``/``river`` at module scope (~2s), which
would be paid on every single tool call. The fast, deterministic floor here is
the "objective floor"; the adaptive per-entity layer is a separate, warm-process
slice.
"""

from __future__ import annotations

import json
from typing import Any

from doberman.config import load_mode
from doberman.engine.decision_engine import PASS_STUB, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.models import Decision, EvalContext, Verdict
from doberman.proxy.normalize import normalize

#: Claude Code built-in tools whose *action* we gate before execution. Pure reads
#: (Read / Glob / Grep) are deliberately NOT gated here — a read cannot destroy or
#: exfiltrate on its own; its *output* is the concern, scanned by the PostToolUse
#: hook (a later slice). Internal tools (TodoWrite, Task, …) are not real-resource
#: actions and abstain too.
GATED_BUILTINS: frozenset[str] = frozenset(
    {"Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch"}
)

#: Map a Claude Code built-in to ``(canonical_tool_name, {src_key: dst_key})`` so
#: :func:`doberman.proxy.normalize.normalize` maps it to the right ``ActionType``
#: and finds the target in a key it recognises (``path`` / ``command`` / ``url``).
#: MCP tools (``mcp__server__tool``) are passed through verbatim — normalize's
#: generic egress/target extraction handles their arbitrary, server-defined schemas.
_BUILTIN_TOOL: dict[str, tuple[str, dict[str, str]]] = {
    "Bash": ("bash", {}),  # {command} — already a target key
    "Edit": ("file_write", {"file_path": "path"}),
    "Write": ("file_write", {"file_path": "path"}),
    "NotebookEdit": ("file_write", {"notebook_path": "path"}),
    # Read is NOT in GATED_BUILTINS (reads abstain pre). This mapping is a
    # forward-declaration for the PostToolUse output-scan slice, which WILL gate
    # reads; it is unreached until then.
    "Read": ("read_file", {"file_path": "path"}),
    "WebFetch": ("http_request", {}),  # {url, prompt} — url is a target/egress key
    # WebSearch is intentionally NOT remapped: its `query` is search *content*, not
    # a routable destination. Mapping query->url made normalize treat the query as
    # an external destination and AUTH'd every search (alert fatigue). Passed
    # through, it normalises to a no-destination action whose query is still scanned
    # for secrets.
}

#: A gated built-in must expose the field that identifies its action; if that field
#: is absent or empty we cannot see what we are being asked to gate, so we fail
#: closed (deny) rather than abstain. MCP tools have arbitrary, server-defined
#: schemas and therefore no required-field check — normalize's generic extraction
#: plus the engine handle them.
_REQUIRED_FIELD: dict[str, str] = {
    "Bash": "command",
    "Edit": "file_path",
    "Write": "file_path",
    "NotebookEdit": "notebook_path",
    "WebFetch": "url",
    "WebSearch": "query",
}

_HOOK_EVENT = "PreToolUse"
_REASON = "Doberman [{verdict}]: {explanation} (reasons: {reasons}; action {action_id})"
_FAILSAFE_REASON = "Doberman: failing closed — could not evaluate this action safely."


def to_normalize_input(
    tool_name: str, tool_input: dict[str, Any] | None
) -> tuple[str, dict[str, Any]]:
    """Translate a Claude Code tool call into ``normalize()``'s ``(name, args)``.

    Built-ins are remapped to a canonical name + target key; everything else
    (notably ``mcp__*`` tools) is passed through so normalize's generic handling
    applies. Never raises.
    """
    args = dict(tool_input or {})
    canonical, renames = _BUILTIN_TOOL.get(tool_name, (tool_name, {}))
    for src, dst in renames.items():
        # If dst is already present (agent sent both, e.g. file_path AND path),
        # keep dst and leave src untouched rather than clobbering dst.
        if src in args and dst not in args:
            args[dst] = args.pop(src)
    return canonical, args


def _decision_payload(decision: Decision) -> dict[str, Any]:
    """Build the PreToolUse hook output for an AUTH (ask) / BLOCK (deny) verdict."""
    permission = "deny" if decision.final_verdict is Verdict.BLOCK else "ask"
    reason = _REASON.format(
        verdict=decision.final_verdict.name,
        explanation=(decision.explanation or "").strip() or "no further detail",
        reasons=", ".join(str(rc) for rc in decision.reason_codes) or "unspecified",
        action_id=decision.action_id,
    )
    return _hook_output(permission, reason)


def _hook_output(permission: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": _HOOK_EVENT,
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    }


def _deny(reason: str = _FAILSAFE_REASON) -> dict[str, Any]:
    return _hook_output("deny", reason)


def evaluate_pre(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Decide one ``PreToolUse`` call.

    Returns the hook-output dict for an AUTH/BLOCK (or a fail-closed deny), or
    ``None`` to abstain (a PASS, or a tool we don't gate before execution).
    NEVER raises — any failure becomes a deny.
    """
    try:
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            return _deny()  # no identifiable action -> refuse
        if not tool_name.startswith("mcp__") and tool_name not in GATED_BUILTINS:
            return None  # reads & internal tools: abstain pre (the post-hook owns output)

        raw_input = payload.get("tool_input")
        tool_input = raw_input if isinstance(raw_input, dict) else {}

        # Fail closed: a gated built-in whose required input field is missing/empty
        # is an action we cannot actually see — refuse it rather than abstain.
        required = _REQUIRED_FIELD.get(tool_name)
        if required is not None:
            value = tool_input.get(required)
            if not isinstance(value, str) or not value.strip():
                return _deny()

        cwd = payload.get("cwd")
        repo_root = cwd if isinstance(cwd, str) and cwd else "."

        canonical, args = to_normalize_input(tool_name, tool_input)
        action = normalize(canonical, args)
        # The objective rules inspect the UN-redacted call via metadata['raw_arguments']
        # (in-memory only, never logged). role=None ⇒ role-boundary rule no-ops; the
        # deterministic floor (paths, destructive commands, destinations, secrets,
        # token channels) is what fires here.
        ctx = EvalContext(
            role=None,
            mode=load_mode(repo_root),
            metadata={"raw_arguments": args, "repo_root": repo_root},
        )
        decision = decide(action, ObjectiveGuardrail(), PASS_STUB, ctx)
        if decision.final_verdict is Verdict.PASS:
            return None  # raise-only: abstain, leaving the harness's native flow intact
        return _decision_payload(decision)
    except Exception:  # noqa: BLE001 — fail closed; never surface the payload in an error
        return _deny()


def run_pre_hook(stdin_text: str) -> str | None:
    """Parse the hook stdin, evaluate, and return the JSON string to print to
    stdout — or ``None`` to abstain (print nothing).

    A payload that does not parse to a JSON object is denied: an unidentifiable
    call fails closed rather than slipping through.
    """
    try:
        payload = json.loads(stdin_text)
    except Exception:  # noqa: BLE001 — unparseable input denies the unknown call
        return json.dumps(_deny())
    if not isinstance(payload, dict):
        return json.dumps(_deny())
    out = evaluate_pre(payload)
    return json.dumps(out) if out is not None else None
