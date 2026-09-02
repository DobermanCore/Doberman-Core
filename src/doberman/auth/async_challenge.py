"""Non-blocking auth-challenge mechanism (Feature 7, issue #144).

Today, :func:`~doberman.auth.challenge.run_auth_challenge` is **synchronous**: it
blocks the calling path — proxy worker, host-hook, or CI pipeline — until a human
decides.  For unattended runs, no human is present; the caller stalls indefinitely
(or until the :data:`~doberman.auth.challenge.DEFAULT_CHALLENGE_TIMEOUT_S` wall-clock
deadline fires and denies).

This module adds an **async (non-blocking) alternative**: the caller issues a challenge
and immediately receives a :class:`ChallengeHandle` — an opaque, action-bound token
it can store or hand to a scheduler. Later, when the human has decided (via any
delivery channel that the operator has wired — dashboard, Slack push, e-mail; the
hosted channels are explicitly out of scope here), the caller resolves the handle and
receives a normal :class:`~doberman.auth.challenge.AuthResult`.

Design constraints (from the issue and project invariants)
----------------------------------------------------------
* **Fail closed** — an unresolved, expired, or error handle yields a non-approved
  ``AuthResult``; it never silently passes.
* **Single-use, action-bound** — a handle resolves exactly once and is permanently
  tied to the ``action_id`` it was issued for.  A second resolve of the same handle
  returns the first result; a handle cannot be used against a different action.
* **No weakening of the existing guarantees** — tier selection, ``role_elevation``
  semantics, and the audit trail are unchanged; the async path is an alternative
  *entry point*, not a replacement of the core machinery.
* **Decoupled from delivery channels** — this module knows nothing about how the
  human is notified.  The "hosted delivery channels (Slack/push/email routing)" are
  explicitly out of scope (see the issue).
* **Entry-point registry** — callers wiring an alternative async backend register an
  :class:`AsyncChallengeBackend` under the ``doberman.async_challenge_backends``
  group; with nothing installed the in-process in-memory backend runs.
* **Import-linter safe** — this module lives in ``doberman.auth`` and therefore must
  not import ``doberman.proxy``, ``doberman.hosthooks``, ``doberman.dash``, or
  ``doberman.turngate``.

Quick-start for operators
-------------------------
1. Call :func:`issue_challenge` from your agent's tool-call path; store the returned
   :class:`ChallengeHandle`.
2. Deliver the challenge details to a human out-of-band (this module does not do that).
3. When the human approves/denies, call :func:`resolve_challenge` with the handle
   and the human's decision.
4. Consume the :class:`~doberman.auth.challenge.AuthResult` from the handle's
   ``result`` property (or ``await handle.wait()``).

Thread / async safety
---------------------
:class:`InMemoryAsyncBackend` is thread-safe (uses :mod:`threading` primitives).
All public functions are synchronous and safe to call from any thread; no event loop
is required.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from pydantic import AwareDatetime

from doberman.auth.challenge import (
    AuthResult,
    AuthTier,
    select_tier,
)
from doberman.models import Decision, SecurityObject

logger = logging.getLogger("doberman.auth.async_challenge")

# ---------------------------------------------------------------------------
# Default TTL for an unresolved handle (seconds).
# Sized well above the worst-case deliberate-human latency for async delivery
# (e.g. a Slack notification that arrives while the human is in a meeting) but
# short enough that a forgotten handle does not accumulate indefinitely.
# ---------------------------------------------------------------------------
DEFAULT_HANDLE_TTL_S: float = 3600.0  # 1 hour

#: ``AuthResult.method`` when the handle expired before any human resolved it.
ASYNC_TIMEOUT_METHOD = "async_timeout"

#: ``AuthResult.method`` when the handle was explicitly denied without TOTP.
ASYNC_DENIED_METHOD = "async_denied"

#: Entry-point group for alternative async backends (mirrors the constant in
#: ``doberman.engine.registry.ASYNC_CHALLENGE_BACKEND_GROUP`` — kept here too
#: so the auth layer can reference it without importing the engine layer, which
#: would violate the import-linter policy-core contract).
ASYNC_BACKEND_GROUP = "doberman.async_challenge_backends"


# ---------------------------------------------------------------------------
# ChallengeHandle — the opaque token returned to the caller
# ---------------------------------------------------------------------------


@dataclass
class ChallengeHandle:
    """An opaque, action-bound token for a pending async challenge.

    Attributes
    ----------
    handle_id:
        Opaque unique identifier for this challenge instance.  Use it to correlate
        the pending row in your delivery channel with the resolve call later.
    action_id:
        The ``SecurityObject.id`` this challenge was issued for.  A resolve call
        MUST carry the same ``action_id`` (enforced by :func:`resolve_challenge`).
    tier:
        The :class:`~doberman.auth.challenge.AuthTier` the engine selected.  Pass
        this to the delivery channel so the human knows what proof is expected.
    issued_at:
        Wall-clock UTC timestamp of the :func:`issue_challenge` call.
    expires_at:
        After this point the handle is considered dead; :func:`resolve_challenge`
        returns a non-approved ``AuthResult`` with ``method = ASYNC_TIMEOUT_METHOD``.
    _event:
        Internal :class:`threading.Event`; set when the handle is resolved.
    _result:
        Internal slot; set (exactly once) when the handle is resolved.
    _lock:
        Guards the single-write invariant on ``_result``.
    """

    handle_id: str
    action_id: str
    tier: AuthTier
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    # --- internal, not part of the public API ---
    _event: threading.Event = field(default_factory=threading.Event, repr=False)
    _result: AuthResult | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @property
    def is_expired(self) -> bool:
        """True if the wall-clock deadline has passed."""
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def is_resolved(self) -> bool:
        """True if a human (or the expiry path) has already resolved this handle."""
        return self._event.is_set()

    @property
    def result(self) -> AuthResult | None:
        """The ``AuthResult`` if resolved, else ``None``.

        Prefer :meth:`wait` when you need the result and can afford to block.
        """
        return self._result

    # ------------------------------------------------------------------
    # Blocking wait (optional; callers that prefer polling use ``result``)
    # ------------------------------------------------------------------

    def wait(self, timeout: float | None = None) -> AuthResult:
        """Block until the handle is resolved, then return the result.

        If ``timeout`` is given and the handle is not resolved in time, the
        method returns a synthesised non-approved result with
        ``method = ASYNC_TIMEOUT_METHOD`` (it does NOT mark the handle as resolved —
        a concurrent resolver can still settle it).

        Parameters
        ----------
        timeout:
            Maximum seconds to wait.  ``None`` waits until the expiry deadline
            computed at issue time.
        """
        deadline_s: float | None
        if timeout is not None:
            deadline_s = timeout
        else:
            remaining = (self.expires_at - datetime.now(timezone.utc)).total_seconds()
            deadline_s = max(remaining, 0.0)

        self._event.wait(timeout=deadline_s)
        if self._result is not None:
            return self._result
        # Timed out waiting — return a synthesised non-approved result.
        return AuthResult(
            approved=False,
            tier=self.tier,
            method=ASYNC_TIMEOUT_METHOD,
            at=datetime.now(timezone.utc),
            action_id=self.action_id,
        )

    # ------------------------------------------------------------------
    # Internal resolution (called by the backend, not by callers)
    # ------------------------------------------------------------------

    def _settle(self, result: AuthResult) -> bool:
        """Record the result (exactly once) and wake any :meth:`wait` callers.

        Returns ``True`` if THIS call was the one that settled the handle;
        ``False`` if the handle was already resolved (idempotent, race-safe).
        """
        with self._lock:
            if self._event.is_set():
                return False  # already settled — idempotent
            self._result = result
            self._event.set()
            return True


# ---------------------------------------------------------------------------
# AsyncChallengeBackend Protocol — the extension seam
# ---------------------------------------------------------------------------


@runtime_checkable
class AsyncChallengeBackend(Protocol):
    """A backend that manages the lifecycle of async challenge handles.

    Implementations live in core (:class:`InMemoryAsyncBackend`) or in installed
    packages registered via ``doberman.async_challenge_backends``.

    Security contract
    -----------------
    * ``issue`` must return a :class:`ChallengeHandle` whose ``action_id`` matches
      ``action.id``.  The handle is single-use; a second :meth:`resolve` of the same
      ``handle_id`` must be a no-op (return the first result).
    * ``resolve`` must reject an ``action_id`` mismatch (fail closed).
    * ``resolve`` called on an expired handle must return a non-approved result.
    """

    def issue(
        self,
        decision: Decision,
        action: SecurityObject,
        tier: AuthTier,
        *,
        ttl_s: float = DEFAULT_HANDLE_TTL_S,
        at: datetime | None = None,
    ) -> ChallengeHandle: ...

    def resolve(
        self,
        handle: ChallengeHandle,
        *,
        approved: bool,
        totp_code: str | None = None,
        at: datetime | None = None,
    ) -> AuthResult: ...

    def expire_stale(self, *, now: datetime | None = None) -> int: ...


# ---------------------------------------------------------------------------
# Built-in in-process backend (no external dependencies)
# ---------------------------------------------------------------------------


class InMemoryAsyncBackend:
    """In-process, thread-safe async challenge backend.

    Handles live in a dictionary keyed by ``handle_id``.  Suitable for single-process
    deployments (CLI, local proxy); a multi-process deployment (e.g. the dashboard
    running in a separate server) should supply a database-backed backend registered
    via the entry-point group.

    This is intentionally the simplest correct backend — it demonstrates the interface
    and serves as the default when nothing else is installed.
    """

    name = "in_memory"

    def __init__(self) -> None:
        self._handles: dict[str, ChallengeHandle] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # AsyncChallengeBackend implementation
    # ------------------------------------------------------------------

    def issue(
        self,
        decision: Decision,
        action: SecurityObject,
        tier: AuthTier,
        *,
        ttl_s: float = DEFAULT_HANDLE_TTL_S,
        at: datetime | None = None,
    ) -> ChallengeHandle:
        """Register a new pending challenge and return the handle.

        The handle is stored internally; pass it (or at least ``handle_id``) to
        :func:`resolve_challenge` when the human decides.
        """
        when = at or datetime.now(timezone.utc)
        from datetime import timedelta  # local import to keep the module header clean

        handle = ChallengeHandle(
            handle_id=uuid.uuid4().hex,
            action_id=action.id,
            tier=tier,
            issued_at=when,
            expires_at=when + timedelta(seconds=ttl_s),
        )
        with self._lock:
            self._handles[handle.handle_id] = handle
        logger.debug(
            "async challenge issued: handle=%s action=%s tier=%s",
            handle.handle_id,
            action.id,
            tier.value,
        )
        return handle

    def resolve(
        self,
        handle: ChallengeHandle,
        *,
        approved: bool,
        totp_code: str | None = None,
        at: datetime | None = None,
    ) -> AuthResult:
        """Settle ``handle`` with the human's decision.

        Returns the :class:`~doberman.auth.challenge.AuthResult` (same value on
        repeated calls — idempotent once settled).

        Raises
        ------
        KeyError
            If ``handle.handle_id`` was never issued by this backend.
        ValueError
            If the handle's ``action_id`` does not match the stored record (tamper
            protection — fail closed).
        """
        when = at or datetime.now(timezone.utc)

        with self._lock:
            stored = self._handles.get(handle.handle_id)
            if stored is None:
                raise KeyError(f"unknown handle: {handle.handle_id!r}")
            if stored.action_id != handle.action_id:
                # The caller supplied a handle that references a different action —
                # this must never approve (fail closed).
                raise ValueError(
                    f"handle {handle.handle_id!r} is bound to action "
                    f"{stored.action_id!r}, not {handle.action_id!r}"
                )

        # Check expiry AFTER the lock (avoids a race where we expire while
        # still inside the critical section).
        if stored.is_expired:
            result = _timeout_result(stored, when)
            stored._settle(result)  # mark resolved so expire_stale won't re-count it
            return result

        # Already resolved?  Return the first result (idempotent).
        if stored.is_resolved and stored.result is not None:
            return stored.result

        # Determine the approval method.  Two-factor tiers require a TOTP code;
        # we verify it here in-process.  A future backend may delegate this to a
        # hosted TOTP service — that is intentionally out of scope for this module.
        method: str
        actual_approved: bool
        if approved and handle.tier in (AuthTier.two_factor, AuthTier.role_elevation):
            if not totp_code:
                # Tier requires a code but none was supplied — deny (fail closed).
                logger.warning(
                    "async resolve for handle %s denied: 2FA tier but no TOTP code supplied",
                    handle.handle_id,
                )
                actual_approved = False
                method = "denied_no_code"
            else:
                from doberman.auth import totp as totp_mod  # lazy: avoids import cycle

                code_ok = totp_mod.verify(totp_code)
                actual_approved = code_ok
                method = "totp" if handle.tier is AuthTier.two_factor else "totp+elevation"
                if not code_ok:
                    logger.warning(
                        "async resolve for handle %s denied: TOTP verification failed",
                        handle.handle_id,
                    )
        elif approved:
            actual_approved = True
            method = handle.tier.value
        else:
            actual_approved = False
            method = ASYNC_DENIED_METHOD

        result = AuthResult(
            approved=actual_approved,
            tier=handle.tier,
            method=method,
            at=when,
            action_id=handle.action_id,
        )
        settled = stored._settle(result)
        if not settled:
            # Another thread resolved first — return what they stored.
            return stored.result  # type: ignore[return-value]

        logger.debug(
            "async challenge resolved: handle=%s action=%s approved=%s method=%s",
            handle.handle_id,
            handle.action_id,
            actual_approved,
            method,
        )
        return result

    def expire_stale(self, *, now: datetime | None = None) -> int:
        """Settle all expired, unresolved handles with a timeout result.

        Call periodically to reclaim memory and close out abandoned challenges.
        Returns the number of handles that were expired by this call.
        """
        when = now or datetime.now(timezone.utc)
        expired_count = 0
        with self._lock:
            stale = [h for h in self._handles.values() if h.is_expired and not h.is_resolved]
        for handle in stale:
            result = _timeout_result(handle, when)
            if handle._settle(result):
                expired_count += 1
                logger.debug(
                    "async challenge expired: handle=%s action=%s",
                    handle.handle_id,
                    handle.action_id,
                )
        return expired_count


# ---------------------------------------------------------------------------
# Module-level singleton and registry helpers
# ---------------------------------------------------------------------------

#: The built-in backend, constructed once at import time.
IN_MEMORY_BACKEND = InMemoryAsyncBackend()


def _looks_like_async_backend(obj: object) -> bool:
    """Structural duck-type check (not just isinstance)."""
    return callable(getattr(obj, "issue", None)) and callable(getattr(obj, "resolve", None))


def active_async_backend() -> AsyncChallengeBackend:
    """Return the active async backend: the first registered one, else in-memory.

    Discovery uses the ``doberman.async_challenge_backends`` entry-point group
    (consistent with the :func:`~doberman.auth.provider.active_provider` pattern),
    gated by the same opt-in-by-name plugins allowlist as every other seam
    (:mod:`doberman.engine.plugin_config` — ``doberman plugins enable <name>``).
    With nothing enabled, the in-memory backend runs and behaviour is identical
    to core-only.
    """
    from doberman.engine.registry import (  # lazy: avoids import cycle at load time
        _iter_allowed_entry_points,
        _load_and_construct,
    )

    for entry_point in _iter_allowed_entry_points(ASYNC_BACKEND_GROUP):
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        if _looks_like_async_backend(candidate):
            return candidate  # type: ignore[return-value]
        logger.warning(
            "skipping async challenge backend %r: not backend-shaped",
            getattr(entry_point, "name", "?"),
        )
    return IN_MEMORY_BACKEND


# ---------------------------------------------------------------------------
# Public convenience functions (the primary API surface)
# ---------------------------------------------------------------------------


def issue_challenge(
    decision: Decision,
    action: SecurityObject,
    *,
    ttl_s: float = DEFAULT_HANDLE_TTL_S,
    at: datetime | None = None,
    backend: AsyncChallengeBackend | None = None,
) -> ChallengeHandle:
    """Issue a non-blocking auth challenge and return a pending handle.

    The calling path is **never** blocked: the tier is selected immediately and the
    handle is registered with the active (or supplied) backend, but no prompt is
    shown and no human interaction occurs here.  The caller is responsible for
    delivering the challenge details to the human through whatever out-of-band
    channel is appropriate.

    Parameters
    ----------
    decision:
        The ``AUTH`` decision from the engine.  ``select_tier`` will raise
        ``ValueError`` if this is not an ``AUTH`` decision.
    action:
        The :class:`~doberman.models.SecurityObject` the challenge names.
    ttl_s:
        Lifetime (seconds) before the handle expires.  After expiry,
        :func:`resolve_challenge` returns a non-approved timeout result.
    at:
        Override the issue timestamp (for testing / deterministic audit logs).
    backend:
        Override the active backend (for testing or DI).  Defaults to
        :func:`active_async_backend()`.
    """
    tier = select_tier(decision)  # validates that decision is AUTH; raises ValueError otherwise
    _backend = backend or active_async_backend()
    handle = _backend.issue(decision, action, tier, ttl_s=ttl_s, at=at)
    logger.info(
        "async auth challenge issued: handle=%s action=%s tier=%s expires=%s",
        handle.handle_id,
        action.id,
        tier.value,
        handle.expires_at.isoformat(),
    )
    return handle


def resolve_challenge(
    handle: ChallengeHandle,
    *,
    approved: bool,
    totp_code: str | None = None,
    at: datetime | None = None,
    backend: AsyncChallengeBackend | None = None,
) -> AuthResult:
    """Resolve a pending challenge handle with the human's decision.

    This is idempotent: a second call for the same handle returns the original
    result without re-running any verification logic.

    Parameters
    ----------
    handle:
        The :class:`ChallengeHandle` returned by :func:`issue_challenge`.
    approved:
        ``True`` if the human approved; ``False`` to deny.
    totp_code:
        Required for ``two_factor`` and ``role_elevation`` tiers.  Pass ``None``
        for ``soft_confirm`` and ``local_auth``.
    at:
        Override the resolution timestamp.
    backend:
        Override the active backend (for testing or DI).

    Returns
    -------
    AuthResult
        The single-use, action-bound approval result.  ``approved`` may differ
        from the ``approved`` parameter when TOTP verification fails.
    """
    _backend = backend or active_async_backend()
    result = _backend.resolve(handle, approved=approved, totp_code=totp_code, at=at)
    logger.info(
        "async auth challenge resolved: handle=%s action=%s approved=%s method=%s",
        handle.handle_id,
        handle.action_id,
        result.approved,
        result.method,
    )
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _timeout_result(handle: ChallengeHandle, at: datetime) -> AuthResult:
    """Synthesise the canonical timeout result for an expired handle."""
    return AuthResult(
        approved=False,
        tier=handle.tier,
        method=ASYNC_TIMEOUT_METHOD,
        at=at,
        action_id=handle.action_id,
    )
