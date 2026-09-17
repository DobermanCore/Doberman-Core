"""The warm, observe-only ambient daemon (FM.2, issue #237).

``doberman monitor run`` hosts the decision engine warm and turns non-inline
activity — everything the FM.1 bus's collectors see — into decision-log
rows. It is a second, independent CONSUMER of the ambient bus FM.1 built; it
never sits on, and cannot affect, the live inline gate
(``doberman.proxy.executor``), which remains the only enforcement point
whether this daemon is running, crashed, or was never started at all.

Each tick:

1. **Poll** every collector in the list ``run_forever`` discovered ONCE at
   startup (:func:`_poll_collectors`) and ``emit_activity_event`` whatever
   they ``collect()`` onto the FM.1 bus. Collector instances are retained
   across ticks, not rebuilt each time — a collector that keeps internal
   state (an open connection, a "last scanned" position) needs that state to
   survive between ticks. Per-collector *and* per-event isolation: a raising
   collector, or one bad event among good ones from the SAME collector, only
   ever costs that collector's own events for this tick.
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
   writer produces, which ``doberman.explain``/``doberman.render``/``doberman.tui``/
   ``doberman.dash`` all key off to prefix every rendered explanation with
   "observed (not enforced): " and keep every verdict badge and aggregate
   count from ever reading as if this were actually blocked or challenged.
   An ambient AUTH/BLOCK-grade verdict is an alert row, nothing more. A
   *write* failure here (the row did not durably land) holds the bus cursor
   back rather than losing the alert — see :func:`run_tick`.

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
* **Single-instance admission is atomic.** :func:`_acquire_lock` claims a
  dedicated lock file with ``O_CREAT | O_EXCL`` — a single OS-level syscall,
  so two processes racing to start at the same instant can never both win
  (a plain heartbeat-freshness check has exactly this gap; the lock file
  closes it). A stale lock (owner crashed) is detected via heartbeat
  freshness and reclaimed rather than blocking every future start forever.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

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
from doberman.storage.db import CONFIG_DIR
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


def _poll_collectors(collectors: Sequence[object]) -> list[ActivityEvent]:
    """Call ``collect()`` on every collector in ``collectors``, isolating failures.

    ``collectors`` are discovered ONCE, by :func:`run_forever`, and the SAME
    instances are passed to every tick — this function never calls
    ``discover_collectors()`` itself. A collector that keeps internal state
    across calls (an open connection, a "last scanned" position so it doesn't
    rescan everything every tick) needs that state to survive between ticks;
    re-instantiating fresh objects each tick (the previous design) silently
    discarded it every time.

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
    for collector in collectors:
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
        except Exception as exc:  # noqa: BLE001 — one bad collector must never break the tick
            logger.warning(
                "monitor: collector %s raised during collect() (%s); skipping its events "
                "for this tick",
                collector_name,
                type(exc).__name__,
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
) -> tuple[bool, bool]:
    """Score one drained event and record it as an ambient decision row.

    Returns ``(clean, written)``:

    * ``clean`` — ``True`` on a clean score, ``False`` when the conservative
      fallback row was recorded instead of a real score. Reconstruction and
      scoring are isolated in their own try/except (:func:`_conservative_fallback`
      is the recovery path) — a poisoned event becomes an alert, never a crash.
    * ``written`` — whether the row actually landed durably
      (``storage.log.record_decision``'s return value). ``run_tick`` uses
      this, not ``clean``, to decide whether it's safe to advance the bus
      cursor past this event: a *scoring* failure still produces a row (the
      conservative fallback) that itself might or might not persist, and a
      *write* failure can happen to an otherwise cleanly-scored event too —
      the two failure modes are independent, so collapsing them into one
      bool would let a clean score with a failed write look identical to a
      genuinely durable one, and the cursor would wrongly move past it.
    """
    try:
        action = _security_object_from_event(event)
        ctx = _build_eval_context(event, mode=mode, repo_root=repo_root)
        decision = decide(action, objective, subjective, ctx)
        clean = True
    except Exception as exc:  # noqa: BLE001 — a poisoned event must become an alert, not a crash
        logger.warning(
            "monitor: scoring failed for event from collector %s (%s); recording a "
            "conservative alert",
            event.collector_id,
            type(exc).__name__,
        )
        action, decision = _conservative_fallback(event)
        clean = False

    written = await record_decision(
        decision,
        action,
        repo_root=repo_root,
        entity_id=event.entity_fingerprint,
        session_id=event.session_fingerprint,
        source_context_override=f"ambient:{event.collector_id}",
    )
    if not written:
        logger.warning(
            "monitor: could not record a decision row for event from collector %s; "
            "will retry next tick",
            event.collector_id,
        )
    return clean, written


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
    collectors: Sequence[object],
    *,
    mode: str = "balanced",
    reader_id: str = DEFAULT_READER_ID,
    batch_limit: int = DEFAULT_BATCH_LIMIT,
) -> MonitorTickResult:
    """One full monitor tick: poll -> emit -> drain -> score -> save cursor.

    ``collectors`` are discovered ONCE by the caller (:func:`run_forever`)
    and passed in unchanged every tick — see :func:`_poll_collectors`.

    The cursor only ever advances past a fully-durable batch: if EVERY event
    drained this tick was written successfully (:func:`_score_event`'s
    ``written``), the cursor moves to ``new_cursor`` as before. If ANY write
    in the batch failed, the cursor does not move at all this tick, and
    scoring for the rest of the batch stops — a struggling storage layer
    rarely recovers mid-batch, and every event in an unmoved batch is
    retried next tick regardless, so continuing to hammer it serves nothing.
    The trade-off is deliberate and documented at the call site: an event
    already-written earlier in the SAME failed batch gets re-scored and
    re-recorded on retry (a duplicate alert row) rather than risking the
    alternative — advancing past a gap and losing the failed event forever.
    Duplicates are visible and harmless; silent loss of a BLOCK-grade alert
    is not.

    Never raises. Every step above already isolates its own failures; this
    function's own try/except is the last-resort boundary for anything
    unanticipated, because the daemon hard rule is that NOTHING here may ever
    reach ``run_forever``'s loop and stop it — a dead daemon must change
    nothing about the live gate, and a daemon that crashed because of a bug
    in THIS module is momentarily just as dead as one that was never started.
    """
    try:
        collected = _poll_collectors(collectors)
        emitted = await _emit_events(collected, repo_root=repo_root)

        cursor = await load_cursor(repo_root, reader_id=reader_id)
        events, new_cursor = read_activity_events(repo_root, after_id=cursor, limit=batch_limit)

        scored = 0
        fallback = 0
        all_written = True
        for event in events:
            clean, written = await _score_event(
                event, objective, subjective, mode=mode, repo_root=repo_root
            )
            if clean:
                scored += 1
            else:
                fallback += 1
            if not written:
                all_written = False
                break  # retry the whole batch next tick rather than hammer a broken write path

        if all_written and new_cursor != cursor:
            await save_cursor(repo_root, reader_id=reader_id, cursor=new_cursor)

        return MonitorTickResult(
            collected=len(collected),
            emitted=emitted,
            drained=len(events),
            scored=scored,
            fallback=fallback,
            cursor=new_cursor if all_written else cursor,
        )
    except Exception as exc:  # noqa: BLE001 — see the docstring: nothing may escape a tick
        # Error CLASS only, never the message/args/traceback (exc_info=True
        # would attach those) — a future bug elsewhere in the call stack
        # could raise with raw data (a path, an env value) in its message,
        # and this log line must never become the leak that undoes every
        # other redaction in this module.
        logger.warning(
            "monitor: tick failed unexpectedly (%s); continuing to the next tick",
            type(exc).__name__,
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

    A best-effort liveness signal for humans (``doberman monitor status``)
    and for deciding whether a leftover lock file (see :func:`_acquire_lock`)
    is stale or belongs to a genuinely running sibling. NOT itself the
    admission guard — checking freshness and then separately touching the
    heartbeat has a gap a second process starting at the same instant can
    fall through (this is exactly the "duplicate admission during
    simultaneous starts" the lock file below closes). Fails closed to
    ``False`` (storage.heartbeat's own contract) — a missing or unreadable
    heartbeat is never mistaken for a live sibling.
    """
    return heartbeat_is_fresh(repo_root, max_age_s=max_age_s, filename=MONITOR_HEARTBEAT_FILE)


#: The lock file's name, in the same gitignored ``.doberman/`` dir as the
#: heartbeat and the DB. Deliberately a *different* file from the heartbeat:
#: the lock's existence is the admission decision (an atomic OS-level
#: create), the heartbeat's freshness is only ever consulted to tell a
#: stale lock (owner crashed) from a live one.
_MONITOR_LOCK_FILE = "monitor.lock"


def _lock_path(repo_root: str) -> Path:
    return Path(repo_root) / CONFIG_DIR / _MONITOR_LOCK_FILE


def _try_create_lock(repo_root: str) -> bool:
    """Attempt to atomically claim the lock file. ``True`` iff this call won.

    ``O_CREAT | O_EXCL`` is a single OS-level syscall: the filesystem itself
    guarantees that when two processes race this call at the same instant,
    exactly one gets ``True`` and the other gets ``FileExistsError`` — the
    same portable atomic-create primitive ``storage/fingerprint.py`` already
    uses for its key file, chosen for the same reason: no TOCTOU gap, and no
    platform-specific locking API (``fcntl``/``msvcrt``) needed, so this
    works identically on the Linux/macOS and Windows CI runners.

    Touches the heartbeat *inside* this same call, immediately on winning —
    not as a separate later step — so a rival process racing a moment behind
    the winner (see :func:`_acquire_lock`'s stale-lock retry) sees a fresh
    heartbeat right away rather than a narrow window where the lock exists
    but nothing has claimed it as live yet.
    """
    path = _lock_path(repo_root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    except OSError:
        return False
    touch_heartbeat(repo_root, filename=MONITOR_HEARTBEAT_FILE)
    return True


def _acquire_lock(repo_root: str) -> None:
    """Win the single-instance lock or raise :class:`MonitorAlreadyRunning`.

    First attempt: atomic create (see :func:`_try_create_lock`) — this alone
    is what makes admission correct under simultaneous starts, closing the
    race a plain heartbeat-freshness check cannot. If the lock file already
    exists, distinguish stale (its owner crashed without cleaning up — the
    heartbeat is no longer fresh) from live (heartbeat still fresh) using
    :func:`is_already_running`: a live lock means refuse outright; a stale
    one means best-effort steal it (unlink + retry the atomic create once)
    rather than let one crashed process block every future daemon start for
    this repo forever. If the retry also loses — another process won the
    steal race, or a genuine sibling reappeared between the check and the
    retry — refuse; a lock file is only ever removed by its own winner
    below, in :func:`run_forever`'s ``finally``, or by this steal path, so
    there is no unbounded retry loop to worry about.
    """
    if _try_create_lock(repo_root):
        return
    if is_already_running(repo_root):
        raise MonitorAlreadyRunning(
            f"a doberman monitor daemon already appears to be running for "
            f"{repo_root!r} (heartbeat fresher than {MONITOR_HEARTBEAT_MAX_AGE_S:.0f}s)"
        )
    try:
        _lock_path(repo_root).unlink(missing_ok=True)
    except OSError:
        pass
    if not _try_create_lock(repo_root):
        raise MonitorAlreadyRunning(
            f"a doberman monitor daemon already appears to be running for {repo_root!r} "
            "(lost the race to start after a stale lock was cleared)"
        )


def _release_lock(repo_root: str) -> None:
    """Best-effort cleanup on a clean stop — a missed unlink just means the
    next start pays the one-tick stale-lock detour in :func:`_acquire_lock`,
    never a permanently stuck lock (that path always recovers)."""
    try:
        _lock_path(repo_root).unlink(missing_ok=True)
    except OSError:
        pass


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
    anything — via :func:`_acquire_lock`'s atomic lock file, if a sibling
    daemon already holds it for this repo: the single-instance guard belongs
    to the daemon, not just to the CLI's convenience wrapper around it.

    ``stop_event``/``max_ticks`` exist for tests and programmatic embedding:
    ``stop_event`` lets a caller request a prompt stop between ticks;
    ``max_ticks`` bounds the loop so a test never runs forever. Neither is
    exposed on the CLI — Ctrl+C (``KeyboardInterrupt``) is the real stop
    signal there.
    """
    _acquire_lock(repo_root)

    objective, subjective = build_engine_stack()
    try:
        collectors = discover_collectors()
    except Exception as exc:  # noqa: BLE001 — a discovery bug must not block the daemon
        logger.warning(
            "monitor: collector discovery failed at startup (%s); starting with none",
            type(exc).__name__,
        )
        collectors = []
    stop_event = stop_event if stop_event is not None else threading.Event()

    def _heartbeat_loop() -> None:
        while not stop_event.is_set():
            touch_heartbeat(repo_root, filename=MONITOR_HEARTBEAT_FILE)
            stop_event.wait(HEARTBEAT_TOUCH_INTERVAL_S)

    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop, name="doberman-monitor-heartbeat", daemon=True
    )
    heartbeat_thread.start()

    ticks = 0
    try:
        while not stop_event.is_set():
            result = asyncio.run(
                run_tick(
                    repo_root, objective, subjective, collectors, mode=mode, reader_id=reader_id
                )
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
        _release_lock(repo_root)


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
