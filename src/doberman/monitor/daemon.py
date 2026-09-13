"""The warm, observe-only ambient daemon (FM.2, issue #237).

``doberman monitor run`` hosts the decision engine warm and turns non-inline
activity — everything the FM.1 bus's collectors see — into decision-log
rows. It is a second, independent CONSUMER of the ambient bus FM.1 built; it
never sits on, and cannot affect, the live inline gate
(``doberman.proxy.executor``), which remains the only enforcement point
whether this daemon is running, crashed, or was never started at all.

Each tick:

1. **Poll** every collector ``discover_collectors()`` returns and
   ``emit_activity_event`` whatever they ``collect()`` onto the FM.1 bus.
   Per-collector *and* per-event isolation (:func:`_poll_collectors`): a
   raising collector, or one bad event among good ones from the SAME
   collector, only ever costs that collector's own events for this tick.
2. **Drain** the bus from the daemon's own saved cursor
   (``reader_id="monitor"``) — not from step 1's transient in-memory
   results. This is why FM.1 built cursor persistence: draining the
   PERSISTED bus, rather than scoring collect()'s return value directly,
   makes the daemon resumable across a restart with neither replay nor loss.
3. **Score** each drained event through the SAME ``decide()`` the live gate
   uses (:func:`_score_event`), against a *degraded* ``SecurityObject``
   reconstructed from the redacted ``ActivityEvent`` (it only ever carries
   ``target_path_class``, never a raw target — ambient scoring is
   approximate by construction, not a bug). A reconstruction or scoring
   failure records a conservative alert row (``ReasonCode.ambient_scoring_error``)
   instead of raising or dropping the event silently.
4. **Record** every scored event via ``storage.log.record_decision`` with
   ``source_context_override=f"ambient:{collector_id}"`` — a shape no live
   writer produces, which ``doberman.explain`` keys off to prefix every
   rendered explanation with "observed (not enforced): " and to make sure no
   AUTH/BLOCK-grade ambient row is ever rendered as if it were actually
   blocked or challenged. An ambient AUTH/BLOCK-grade verdict is an alert
   row, nothing more.

Hard rules (each one has a dedicated test in ``test_monitor_daemon.py``):

* **Observe-only, structurally.** This module never imports
  ``doberman.auth`` (no prompter, no challenge) or ``doberman.proxy``
  (no executor) — enforced by the import-linter contract in
  ``pyproject.toml`` ("Policy core must not depend on the ambient monitor"
  guards the reverse direction; a dedicated import-graph test here guards
  this one). There is no code path in this module that can block, challenge,
  or execute anything.
* **No learning from ambient input.** This module never calls
  ``doberman.policy.baseline.observe``/``note_allowed``/``note_belief`` or
  any other baseline-writing function — those are wired only into
  ``doberman.proxy.executor``'s hooks, which this module does not import.
  Ambient events are unauthenticated local observations (a poisoning
  surface): they inform an alert row, never a stored baseline.
* **A dead daemon changes nothing about inline protection.** Every tick body
  is wrapped in its own failure boundary (:func:`run_tick`); an unexpected
  bug here can cost this tick's alerts, never the live gate's next decision.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from doberman.engine.decision_engine import Guardrail, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.registry import discover_collectors
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    ActivityEvent,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.preferences import vector_for
from doberman.storage.activity import (
    emit_activity_event,
    load_cursor,
    read_activity_events,
    save_cursor,
)
from doberman.storage.heartbeat import (
    MONITOR_HEARTBEAT_FILE,
    heartbeat_is_fresh,
    heartbeat_path,
    touch_heartbeat,
)
from doberman.storage.log import record_decision

logger = logging.getLogger("doberman.monitor.daemon")

#: The reader_id this daemon saves its bus cursor under (storage.activity's
#: monitor_state table). A name of its own so a future second reader (e.g. a
#: dashboard feed) can drain the same bus independently without racing this
#: daemon's cursor.
DEFAULT_READER_ID = "monitor"

#: How many bus events one tick drains at most - keeps a single tick bounded
#: even after a long gap (daemon was stopped, bus backlog built up).
DEFAULT_BATCH_LIMIT = 200

#: How often run_forever scores a new tick, by default.
DEFAULT_TICK_INTERVAL_S = 5.0

#: A monitor daemon's heartbeat thread ticks at this FIXED cadence,
#: independent of --interval (the SCORING cadence, which may be much
#: longer) - mirrors doberman dash's heartbeat thread
#: (doberman.cli.main.dash / doberman.dash.app). Decoupling liveness from
#: scoring cadence means the single-instance guard below doesn't have to
#: guess at whatever --interval a live sibling was started with.
HEARTBEAT_TOUCH_INTERVAL_S = 2.0

#: A monitor daemon is considered "gone" once its heartbeat is older than
#: this - matches storage.heartbeat.DEFAULT_HEARTBEAT_MAX_AGE_S's own
#: convention for the same reason (a couple of missed 2s touches, not more).
MONITOR_HEARTBEAT_MAX_AGE_S = 5.0

#: How many pending (undrained) bus rows `monitor_status` will count before
#: giving up and reporting a floor - a status call must stay cheap even
#: against a large backlog.
_STATUS_PENDING_LIMIT = 10_000


class MonitorAlreadyRunning(RuntimeError):
    """Raised by :func:`run_forever` when a sibling daemon is already alive.

    The single-instance guard (FM.2 hard rule: "a fresh sibling heartbeat
    means exit with a message") is a property of the daemon itself — this is
    raised from :func:`run_forever` directly, not just checked by the CLI, so
    anything that calls it programmatically gets the same protection.
    """


@dataclass(frozen=True)
class MonitorTickResult:
    """A summary of one :func:`run_tick` call - for ``on_tick`` callers and tests."""

    collected: int
    emitted: int
    drained: int
    scored: int
    fallback: int
    cursor: int


# ---------------------------------------------------------------------------
# Step 1 — poll collectors, emit onto the bus
# ---------------------------------------------------------------------------


def _poll_collectors() -> list[ActivityEvent]:
    """Call ``collect()`` on every discovered collector, isolating failures.

    A collector that raises during ``collect()`` only costs ITS OWN events
    for this tick — events already yielded by an earlier collector (or
    earlier in this collector's own iteration, for a generator that raises
    partway through) are kept. A yielded value that isn't an
    :class:`~doberman.models.ActivityEvent` is logged and skipped rather
    than passed on to :func:`emit_activity_event` (which would reject it
    anyway, but skipping here keeps the rejection reason attributable to the
    right collector).
    """
    events: list[ActivityEvent] = []
    for collector in discover_collectors():
        collector_name = type(collector).__name__
        try:
            for event in collector.collect():
                if isinstance(event, ActivityEvent):
                    events.append(event)
                else:
                    logger.warning(
                        "monitor: collector %s yielded a non-ActivityEvent (%s); skipping",
                        collector_name,
                        type(event).__name__,
                    )
        except Exception:  # noqa: BLE001 — one bad collector must never break the tick
            logger.warning(
                "monitor: collector %s raised during collect(); skipping its events for this tick",
                collector_name,
            )
    return events


async def _emit_events(events: list[ActivityEvent], *, repo_root: str) -> int:
    """Emit every collected event onto the FM.1 bus. Returns the count attempted.

    ``emit_activity_event`` never raises (storage.activity's own contract),
    so no per-event try/except is needed here.
    """
    for event in events:
        await emit_activity_event(event, repo_root=repo_root)
    return len(events)


# ---------------------------------------------------------------------------
# Step 3 — score a drained event through the real decide()
# ---------------------------------------------------------------------------


def _security_object_from_event(event: ActivityEvent) -> SecurityObject:
    """Reconstruct a degraded :class:`SecurityObject` from a redacted event.

    Deliberately approximate: an :class:`ActivityEvent` never carries a raw
    ``target`` (only ``target_path_class``), a ``tool_name``, an ``algebra``,
    or a ``source_context`` — that redaction is FM.1's whole point. Every
    field this daemon cannot recover keeps ``SecurityObject``'s own
    conservative default (``risk=low``, ``source_context=unknown``,
    ``reversibility=medium``) rather than guessing. ``tool_name`` is
    synthesized from the collector, since ``SecurityObject.tool_name`` has no
    default and an ambient event has no real tool call behind it.
    """
    try:
        action_type = ActionType(event.action_type)
    except ValueError:
        action_type = ActionType.other
    return SecurityObject(
        id=event.action_id,
        ts=event.ts,
        agent_role=event.agent_role,
        action_type=action_type,
        tool_name=f"ambient:{event.collector_id}",
        target_path_class=event.target_path_class,
    )


def _build_eval_context(event: ActivityEvent, *, mode: str, repo_root: str) -> EvalContext:
    """The :class:`EvalContext` an ambient event is scored against.

    Mirrors the shape ``doberman.demo._build_eval_context`` pins for a
    scripted scenario, with two ambient-specific differences: ``role=None``
    (role enforcement is opt-in and the role rule abstains on ``None`` — an
    ``ActivityEvent`` carries a bare ``agent_role`` string, not the full
    ``RoleDefinition`` the role rule needs, so resolving one here would be a
    guess) and ``raw_arguments={}`` (the bus never stores raw arguments, so
    any rule reading them degrades to "nothing observed" rather than
    fabricating data — the correct behavior for approximate, observe-only
    scoring).
    """
    return EvalContext(
        role=None,
        mode=mode,
        metadata={
            "raw_arguments": {},
            "repo_root": repo_root,
            "elevations": (),
            "surprise": 0.0,
            "budget_ok": True,
            "scope_token": False,
            "entity_id": event.entity_fingerprint,
            "preferences": vector_for(mode),
        },
    )


def _conservative_fallback(event: ActivityEvent) -> tuple[SecurityObject, Decision]:
    """A safe, always-constructible action + BLOCK-grade alert for when
    scoring an event raises.

    FM.2 hard rule: "a scoring failure records a conservative row rather
    than silence." Built only from fields an already-validated
    :class:`ActivityEvent` guarantees are present (``action_id``, ``ts``,
    ``agent_role``, ``collector_id``), so constructing this fallback cannot
    itself raise. Still just an alert row — see the module docstring — never
    an enforcement action.
    """
    result = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.ambient_scoring_error],
        explanation=(
            "Ambient event scoring failed; recording a conservative alert "
            "instead of dropping it silently."
        ),
    )
    action = SecurityObject(
        id=event.action_id,
        ts=event.ts,
        agent_role=event.agent_role,
        action_type=ActionType.other,
        tool_name=f"ambient:{event.collector_id}",
    )
    decision = Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.high,
        objective=result,
        subjective=None,
        reason_codes=[ReasonCode.ambient_scoring_error],
        explanation=result.explanation,
        decided_at=datetime.now(timezone.utc),
    )
    return action, decision


async def _score_event(
    event: ActivityEvent,
    objective: Guardrail,
    subjective: Guardrail,
    *,
    mode: str,
    repo_root: str,
) -> bool:
    """Score one drained event and record it as an ambient decision row.

    Returns ``True`` on a clean score, ``False`` when the conservative
    fallback row was recorded instead. Never raises: reconstruction and
    scoring are isolated in their own try/except (:func:`_conservative_fallback`
    is the recovery path); ``record_decision`` is already unconditionally
    safe (storage.log's own contract).
    """
    try:
        action = _security_object_from_event(event)
        ctx = _build_eval_context(event, mode=mode, repo_root=repo_root)
        decision = decide(action, objective, subjective, ctx)
        clean = True
    except Exception:  # noqa: BLE001 — a poisoned event must become an alert, not a crash
        logger.warning(
            "monitor: scoring failed for event from collector %s; recording a conservative alert",
            event.collector_id,
        )
        action, decision = _conservative_fallback(event)
        clean = False

    await record_decision(
        decision,
        action,
        repo_root=repo_root,
        entity_id=event.entity_fingerprint,
        session_id=event.session_fingerprint,
        source_context_override=f"ambient:{event.collector_id}",
    )
    return clean


# ---------------------------------------------------------------------------
# One tick, and the engine stack it's built against
# ---------------------------------------------------------------------------


def build_engine_stack() -> tuple[Guardrail, Guardrail]:
    """Build the objective/subjective guardrails ONCE for a daemon run.

    Mirrors ``doberman.demo``'s pattern: construction cost (rule/plugin
    discovery) is paid once per process, not once per tick — only the
    per-event :class:`EvalContext` varies tick to tick.
    """
    return ObjectiveGuardrail(), SubjectiveGuardrail()


async def run_tick(
    repo_root: str,
    objective: Guardrail,
    subjective: Guardrail,
    *,
    mode: str = "balanced",
    reader_id: str = DEFAULT_READER_ID,
    batch_limit: int = DEFAULT_BATCH_LIMIT,
) -> MonitorTickResult:
    """One full monitor tick: poll -> emit -> drain -> score -> save cursor.

    Never raises. Every step above already isolates its own failures; this
    function's own try/except is the last-resort boundary for anything
    unanticipated, because the daemon hard rule is that NOTHING here may ever
    reach ``run_forever``'s loop and stop it — a dead daemon must change
    nothing about the live gate, and a daemon that crashed because of a bug
    in THIS module is momentarily just as dead as one that was never started.
    """
    try:
        collected = _poll_collectors()
        emitted = await _emit_events(collected, repo_root=repo_root)

        cursor = await load_cursor(repo_root, reader_id=reader_id)
        events, new_cursor = read_activity_events(repo_root, after_id=cursor, limit=batch_limit)

        scored = 0
        fallback = 0
        for event in events:
            clean = await _score_event(event, objective, subjective, mode=mode, repo_root=repo_root)
            if clean:
                scored += 1
            else:
                fallback += 1

        if new_cursor != cursor:
            await save_cursor(repo_root, reader_id=reader_id, cursor=new_cursor)

        return MonitorTickResult(
            collected=len(collected),
            emitted=emitted,
            drained=len(events),
            scored=scored,
            fallback=fallback,
            cursor=new_cursor,
        )
    except Exception:  # noqa: BLE001 — see the docstring: nothing may escape a tick
        logger.warning(
            "monitor: tick failed unexpectedly; continuing to the next tick", exc_info=True
        )
        return MonitorTickResult(collected=0, emitted=0, drained=0, scored=0, fallback=0, cursor=-1)


# ---------------------------------------------------------------------------
# Heartbeat, single-instance guard, and the run-forever loop
# ---------------------------------------------------------------------------


def is_already_running(
    repo_root: str = ".",
    *,
    max_age_s: float = MONITOR_HEARTBEAT_MAX_AGE_S,
) -> bool:
    """Whether a monitor daemon's heartbeat for ``repo_root`` is still fresh.

    The single-instance guard's pure, easily-tested check: ``True`` means a
    sibling is already alive for this repo and a second daemon must not
    start. Fails closed to ``False`` (storage.heartbeat's own contract) — a
    missing or unreadable heartbeat is never mistaken for a live sibling.
    """
    return heartbeat_is_fresh(repo_root, max_age_s=max_age_s, filename=MONITOR_HEARTBEAT_FILE)


def run_forever(
    repo_root: str = ".",
    *,
    interval_s: float = DEFAULT_TICK_INTERVAL_S,
    mode: str = "balanced",
    reader_id: str = DEFAULT_READER_ID,
    stop_event: threading.Event | None = None,
    max_ticks: int | None = None,
    on_tick: Callable[[MonitorTickResult], None] | None = None,
) -> None:
    """Run the warm ambient monitor daemon until stopped.

    Builds the engine stack ONCE (:func:`build_engine_stack`), then loops
    :func:`run_tick` every ``interval_s`` seconds. A background thread
    touches the heartbeat every :data:`HEARTBEAT_TOUCH_INTERVAL_S` regardless
    of ``interval_s``, so liveness stays fresh even with a long scoring
    interval (mirrors ``doberman dash``'s own heartbeat thread).

    Raises :class:`MonitorAlreadyRunning` immediately — before building
    anything — if a sibling daemon's heartbeat for this repo is still fresh:
    the single-instance guard belongs to the daemon, not just to the CLI's
    convenience wrapper around it.

    ``stop_event``/``max_ticks`` exist for tests and programmatic embedding:
    ``stop_event`` lets a caller request a prompt stop between ticks;
    ``max_ticks`` bounds the loop so a test never runs forever. Neither is
    exposed on the CLI — Ctrl+C (``KeyboardInterrupt``) is the real stop
    signal there.
    """
    if is_already_running(repo_root):
        raise MonitorAlreadyRunning(
            f"a doberman monitor daemon already appears to be running for "
            f"{repo_root!r} (heartbeat fresher than {MONITOR_HEARTBEAT_MAX_AGE_S:.0f}s)"
        )

    objective, subjective = build_engine_stack()
    stop_event = stop_event if stop_event is not None else threading.Event()

    def _heartbeat_loop() -> None:
        while not stop_event.is_set():
            touch_heartbeat(repo_root, filename=MONITOR_HEARTBEAT_FILE)
            stop_event.wait(HEARTBEAT_TOUCH_INTERVAL_S)

    # Touch once synchronously before the background thread starts, so a
    # status check (or a second is_already_running()) immediately after
    # start-up sees a fresh heartbeat rather than a race against the thread.
    touch_heartbeat(repo_root, filename=MONITOR_HEARTBEAT_FILE)
    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop, name="doberman-monitor-heartbeat", daemon=True
    )
    heartbeat_thread.start()

    ticks = 0
    try:
        while not stop_event.is_set():
            result = asyncio.run(
                run_tick(repo_root, objective, subjective, mode=mode, reader_id=reader_id)
            )
            if on_tick is not None:
                on_tick(result)
            ticks += 1
            if max_ticks is not None and ticks >= max_ticks:
                break
            stop_event.wait(interval_s)
    finally:
        stop_event.set()
        heartbeat_thread.join(timeout=HEARTBEAT_TOUCH_INTERVAL_S * 2)


async def monitor_status(repo_root: str = ".") -> dict:
    """A snapshot for ``doberman monitor status``: liveness, cursor, backlog.

    Never raises — every field falls back to a safe value on any read error,
    so status is always reportable even against a missing or corrupt
    ``.doberman/`` directory.
    """
    now = datetime.now(timezone.utc)
    heartbeat_age_s: float | None = None
    try:
        text = (
            heartbeat_path(repo_root, filename=MONITOR_HEARTBEAT_FILE)
            .read_text(encoding="utf-8")
            .strip()
        )
        stamp = datetime.fromisoformat(text)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        heartbeat_age_s = (now - stamp).total_seconds()
    except (OSError, ValueError):
        heartbeat_age_s = None

    running = heartbeat_age_s is not None and heartbeat_age_s < MONITOR_HEARTBEAT_MAX_AGE_S

    cursor = await load_cursor(repo_root, reader_id=DEFAULT_READER_ID)
    pending_events, _ = read_activity_events(
        repo_root, after_id=cursor, limit=_STATUS_PENDING_LIMIT
    )

    return {
        "running": running,
        "heartbeat_age_s": heartbeat_age_s,
        "cursor": cursor,
        "pending_events": len(pending_events),
    }
