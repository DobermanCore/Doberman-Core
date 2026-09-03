"""Session-replay: exercise the real post-decide floors over a fresh, isolated
per-case session.

``decide()`` alone never triggers ``doberman.engine.taint_floor.
apply_taint_floor_async``, ``apply_echo_tripwire_async``, or
``doberman.engine.correlator.apply_correlator_async`` — those are deliberately
NOT wired into ``decide()`` (see each module's own docstring: the correlator's
cross-call read would never see later legs if it ran inside ``decide()``'s own
short-circuit). In production they run AFTER ``decide()`` returns, over
persisted session state, from ``doberman.proxy.executor`` and
``doberman.hosthooks.spine`` — see those two modules for the canonical apply
order this module mirrors exactly: taint floor, then echo tripwire, then
correlator.

Because the stateless harness (``runner.py`` with ``session_replay=False``)
calls ``decide()`` once per action with no persisted state at all, these three
floors are NEVER exercised by the default harness path — multi-action suites
(AgentDojo/AgentDyn, LLMail-Inject, MSB) therefore under-measure Doberman on
exactly the attack class they encode: untrusted content read in one step,
consummating egress in a later one. ``session_replay=True`` closes that gap by
replaying each ``BenchmarkCase`` in a fresh, isolated session: a temp directory
as ``repo_root`` (a temp SQLite DB) per case, ``session_id = case.case_id``.

Honest scope (no oversell — see the plan's Global Constraint 4):
* The echo tripwire (C1) fires on an EXACT host/URL/email value reused from an
  earlier untrusted read — this is a strong structural match for a pure
  social-engineering injection (e.g. LLMail-Inject: read a phishing email that
  names the attacker's own address, then send to that exact address) and IS
  expected to raise it under replay.
* The taint floor only fires on secret-*shaped* content; the correlator's
  ``correlated_trifecta`` needs a prior row with a secret-class reason code,
  not just any untrusted-provenance row.
* All three floors require ``action.external_destination is not None`` (an
  egress signal) — a consummating action that is a local file write/process
  action with no destination is untouched by any of them, replay or not.

``UNTRUSTED_READ_TOOLS`` (``doberman.engine.taint_floor``) is a real
tool-name allowlist (``{"WebFetch", "WebSearch"}``) gating the untrusted-value
leg of ``record_output_taint`` — it will essentially never match this
harness's suite-neutral tool names. So instead of relying on that gate, an
"untrusted read" here is decided from ``action.source_context ∈
{SourceContext.tool_output, SourceContext.webpage, SourceContext.email}``,
and the untrusted-value taint is recorded by calling the SAME extractor both
real record legs share — ``untrusted_read_value_fingerprints`` — followed by
the real store write, ``record_untrusted_values``, directly. Neither is
re-implemented; both are the unmodified ``src/doberman`` functions.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from doberman.engine.correlator import apply_correlator_async
from doberman.engine.taint_floor import (
    apply_echo_tripwire_async,
    apply_taint_floor_async,
    record_output_taint,
    untrusted_read_value_fingerprints,
)
from doberman.models import SourceContext
from doberman.storage.device_metrics import HOME_ENV
from doberman.storage.fingerprint import KEY_FILE_ENV
from doberman.storage.log import record_decision
from doberman.storage.taint import (
    TAINT_UNTRUSTED_READ,
    entity_scope,
    record_taints,
    record_untrusted_values,
)

from .adapter import BenchmarkCase, CandidateAction
from .mapping import to_eval_context, to_security_object
from .metrics import ActionOutcome
from .profiles import NO_GUARDRAIL

if TYPE_CHECKING:  # avoid a runtime import cycle with runner.py (see below)
    from .runner import DecidingPipeline

#: The harness's own definition of "untrusted read" for taint/echo recording —
#: see the module docstring for why this doesn't use UNTRUSTED_READ_TOOLS.
_UNTRUSTED_READ_CONTEXTS = frozenset(
    {SourceContext.tool_output, SourceContext.webpage, SourceContext.email}
)


def _content_text(action: CandidateAction) -> str:
    """Flatten ``raw_arguments`` to text for the secret/untrusted-value scans —
    mirrors the host-hook's own output coercion (``hosthooks/claude_code.py``'s
    ``_coerce_response_text``) so a synthetic secret or a lure address anywhere
    in the action's arguments is found the same way a real tool result's text
    would be."""
    try:
        return json.dumps(dict(action.raw_arguments), ensure_ascii=False, default=str)
    except Exception:  # noqa: BLE001 — best-effort, mirrors the host-hook's own fallback
        return str(action.raw_arguments)


async def _record_untrusted_read(
    action: CandidateAction, repo_root: str, session_id: str | None
) -> None:
    """Record BOTH taint legs for one untrusted-read action: the secret leg via
    the real ``record_output_taint`` (content-judged, tool-name-independent),
    and the untrusted-VALUE leg by calling the real extractor +  store write
    directly (see the module docstring for why ``record_output_taint``'s own
    gate can't be relied on here)."""
    text = _content_text(action)
    await record_output_taint(text, repo_root, session_id, tool_name=action.tool_name)

    # Mirrors hosthooks/claude_code.py's _record_untrusted_value_fingerprints
    # (~613-619): a failing entity_scope must not break untrusted-read
    # recording, only drop the repo-wide scope.
    scopes: list[str] = [session_id] if session_id else []
    try:
        scopes.append(entity_scope(repo_root))
    except Exception:  # noqa: BLE001,S110 — keep the session scope even if entity scope fails
        pass
    await record_taints(repo_root, scopes, [TAINT_UNTRUSTED_READ])
    values = await untrusted_read_value_fingerprints(text, repo_root, session_id)
    if values:
        await record_untrusted_values(repo_root, scopes, list(values), action.tool_name)


async def _replay_case_async(
    case: BenchmarkCase,
    suite_name: str,
    pipeline: "DecidingPipeline",
    mode: str | None,
    repo_root: str,
) -> list[ActionOutcome]:
    from .runner import _action_bucket  # lazy: runner.py also lazily imports this module

    session_id = case.case_id
    # The "before" (no-guardrail) baseline never gets a floor applied and never
    # writes session state — see Global Constraint 5. It behaves byte-for-byte
    # like the stateless path, just executed through this same loop for
    # uniformity, so `PassthroughPipeline`'s own asr==1.0/fpr==0.0 guarantee
    # cannot be punched through by a raise-only floor.
    is_baseline = pipeline.name == NO_GUARDRAIL

    outcomes: list[ActionOutcome] = []
    for index, action in enumerate(case.actions):
        action_id = f"{suite_name}:{case.case_id}:{index}"
        security_object = to_security_object(action_id, action)
        ctx = to_eval_context(action)
        if mode is not None:
            ctx = ctx.model_copy(update={"mode": mode})
        decision = pipeline.decide(security_object, ctx)

        if not is_baseline:
            args: dict[str, Any] = dict(action.raw_arguments)
            # Same order as doberman.proxy.executor.decide_and_execute and
            # doberman.hosthooks.spine.evaluate: taint floor, echo tripwire,
            # then correlator.
            decision = await apply_taint_floor_async(
                security_object, decision, ctx.mode, repo_root, session_id, args
            )
            decision = await apply_echo_tripwire_async(
                security_object, decision, ctx.mode, repo_root, session_id, args
            )
            decision = await apply_correlator_async(
                security_object, decision, ctx.mode, repo_root, session_id
            )
            # Persist THIS action's row before the NEXT action's correlator
            # read, and record any untrusted-provenance/secret-shaped/echo
            # material THIS action carries — mirrors the real write order.
            await record_decision(
                decision, security_object, repo_root=repo_root, session_id=session_id
            )
            if action.source_context in _UNTRUSTED_READ_CONTEXTS:
                await _record_untrusted_read(action, repo_root, session_id)

        bucket = _action_bucket(case, index)
        if bucket is not None:
            outcomes.append(
                ActionOutcome(
                    bucket=bucket,
                    verdict=decision.final_verdict,
                    reason_codes=tuple(decision.reason_codes),
                )
            )
    return outcomes


def replay_case(
    case: BenchmarkCase, suite_name: str, pipeline: "DecidingPipeline", mode: str | None
) -> list[ActionOutcome]:
    """Evaluate one case with the post-decide floors applied, inside a fresh,
    isolated per-case session (a temp repo root — a temp SQLite DB) so a prior
    case's taint/decision history can never leak into this one via
    ``entity_scope``, which is keyed by repo root alone (see the module
    docstring's "Per-case isolation" rationale in the plan)."""
    with tempfile.TemporaryDirectory(
        prefix="doberman-bench-", ignore_cleanup_errors=True
    ) as repo_root:
        return asyncio.run(_replay_case_async(case, suite_name, pipeline, mode, repo_root))


def _restore_env(name: str, prev: str | None) -> None:
    if prev is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = prev


@contextmanager
def isolated_process_state() -> Iterator[None]:
    """Point the fingerprint HMAC key and the device-global metrics rollup at a
    throwaway directory for the run's duration.

    A session-replay run calls ``storage.log.record_decision`` once per
    replayed action, which unconditionally increments
    ``~/.doberman/metrics.db``'s lifetime "how many times Doberman stepped in"
    dashboard counter, and ``storage.fingerprint.fingerprint()`` lazily
    creates/uses the real per-user HMAC key file on first use. Without this, a
    run of a few hundred/thousand synthetic cases would silently pollute the
    operator's real per-user state. Mirrors ``tests/conftest.py``'s
    ``isolated_fingerprint_key``/``isolated_device_metrics_home`` autouse
    fixtures (which already isolate every pytest test in this task for free)
    for the plain, non-pytest CLI entry point. Restores the previous
    environment values on exit.
    """
    with tempfile.TemporaryDirectory(
        prefix="doberman-bench-state-", ignore_cleanup_errors=True
    ) as state_dir:
        prev_key = os.environ.get(KEY_FILE_ENV)
        prev_home = os.environ.get(HOME_ENV)
        os.environ[KEY_FILE_ENV] = str(Path(state_dir) / "fingerprint.key")
        os.environ[HOME_ENV] = state_dir
        try:
            yield
        finally:
            _restore_env(KEY_FILE_ENV, prev_key)
            _restore_env(HOME_ENV, prev_home)
